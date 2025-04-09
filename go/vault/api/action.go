package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ prettyprint.PrettyPrinter = (*Action)(nil)

// PendingAction is an action waiting for authorizations in order to be executed.
type PendingAction struct {
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
	// AuthorizedBy contains the addresses that have authorized the action.
	AuthorizedBy []staking.Address `json:"authorized_by"`
	// Action is the pending action itself.
	Action Action `json:"action"`
}

// ContainsAuthorizationFrom returns true iff the given address is among the action authorizers.
func (pa *PendingAction) ContainsAuthorizationFrom(addr staking.Address) bool {
	return slices.Contains(pa.AuthorizedBy, addr)
}

// Action is a vault action.
type Action struct {
	// Suspend is the suspend action.
	Suspend *ActionSuspend `json:"suspend,omitempty"`
	// Resume is the resume action.
	Resume *ActionResume `json:"resume,omitempty"`
	// ExecuteMessage is the execute message action.
	ExecuteMessage *ActionExecuteMessage `json:"execute_msg,omitempty"`
	// UpdateWithdrawPolicy is the withdraw policy update action.
	UpdateWithdrawPolicy *ActionUpdateWithdrawPolicy `json:"update_withdraw_policy,omitempty"`
	// UpdateAuthority is the authority update action.
	UpdateAuthority *ActionUpdateAuthority `json:"update_authority,omitempty"`
}

// Validate validates the given action.
func (a *Action) Validate(params *ConsensusParameters) error {
	// Ensure there is at most one action set.
	if !common.ExactlyOneTrue(
		a.Suspend != nil,
		a.Resume != nil,
		a.ExecuteMessage != nil,
		a.UpdateWithdrawPolicy != nil,
		a.UpdateAuthority != nil,
	) {
		return fmt.Errorf("exactly one action must be set")
	}

	// Validate actions that need validation.
	var err error
	switch {
	case a.ExecuteMessage != nil:
		err = a.ExecuteMessage.Validate()
	case a.UpdateWithdrawPolicy != nil:
		err = a.UpdateWithdrawPolicy.Validate()
	case a.UpdateAuthority != nil:
		err = a.UpdateAuthority.Validate(params)
	}
	return err
}

// Equal returns true iff one action is equal to another.
func (a *Action) Equal(other *Action) bool {
	return bytes.Equal(cbor.Marshal(a), cbor.Marshal(other))
}

// Authorities returns the authorities of the given vault that can authorize this action.
func (a *Action) Authorities(vault *Vault) []*Authority {
	switch {
	case a.Suspend != nil:
		return a.Suspend.Authorities(vault)
	case a.Resume != nil:
		return a.Resume.Authorities(vault)
	case a.ExecuteMessage != nil:
		return a.ExecuteMessage.Authorities(vault)
	case a.UpdateWithdrawPolicy != nil:
		return a.UpdateWithdrawPolicy.Authorities(vault)
	case a.UpdateAuthority != nil:
		return a.UpdateAuthority.Authorities(vault)
	default:
		return nil
	}
}

// IsAuthorized returns true iff the given address is authorized to execute this action.
func (a *Action) IsAuthorized(vault *Vault, addr staking.Address) bool {
	for _, auth := range a.Authorities(vault) {
		if auth.Contains(addr) {
			return true
		}
	}
	return false
}

// PrettyPrint writes a pretty-printed representation of Action to the given writer.
func (a Action) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	if a.Suspend != nil {
		fmt.Fprintf(w, "%sSuspend vault\n", prefix)
	}
	if a.Resume != nil {
		fmt.Fprintf(w, "%sResume vault\n", prefix)
	}
	if a.ExecuteMessage != nil {
		fmt.Fprintf(w, "%sExecute message:\n", prefix)
		a.ExecuteMessage.PrettyPrint(ctx, prefix+"  ", w)
	}
	if a.UpdateWithdrawPolicy != nil {
		fmt.Fprintf(w, "%sUpdate withdraw policy:\n", prefix)
		a.UpdateWithdrawPolicy.PrettyPrint(ctx, prefix+"  ", w)
	}
	if a.UpdateAuthority != nil {
		fmt.Fprintf(w, "%sUpdate authority:\n", prefix)
		a.UpdateAuthority.PrettyPrint(ctx, prefix+"  ", w)
	}
}

// PrettyType returns a representation of Action that can be used for pretty printing.
func (a Action) PrettyType() (any, error) {
	return a, nil
}

// ActionSuspend is the action to suspend the vault.
type ActionSuspend struct{}

// Authorities returns the authorities of the given vault that can authorize this action.
func (as *ActionSuspend) Authorities(vault *Vault) []*Authority {
	return []*Authority{
		&vault.AdminAuthority,
		&vault.SuspendAuthority,
	}
}

// ActionResume is the action to suspend the vault.
type ActionResume struct{}

// Authorities returns the authorities of the given vault that can authorize this action.
func (ar *ActionResume) Authorities(vault *Vault) []*Authority {
	return []*Authority{
		&vault.AdminAuthority,
		&vault.SuspendAuthority,
	}
}

// ActionExecuteMessage is the action to execute a message on behalf of the vault. The message is
// dispatched as if the vault originated a transaction.
type ActionExecuteMessage struct {
	// Method is the method that should be called.
	Method transaction.MethodName `json:"method"`
	// Body is the method call body.
	Body cbor.RawMessage `json:"body,omitempty"`
}

// Validate validates the given action.
func (am *ActionExecuteMessage) Validate() error {
	if err := am.Method.SanityCheck(); err != nil {
		return fmt.Errorf("malformed execute message method")
	}
	return nil
}

// Authorities returns the authorities of the given vault that can authorize this action.
func (am *ActionExecuteMessage) Authorities(vault *Vault) []*Authority {
	return []*Authority{
		&vault.AdminAuthority,
	}
}

// PrettyPrintBody writes a pretty-printed representation of the message body to the given writer.
func (am ActionExecuteMessage) PrettyPrintBody(ctx context.Context, prefix string, w io.Writer) {
	bodyType := am.Method.BodyType()
	if bodyType == nil {
		fmt.Fprintf(w, "%s<unknown method body: %s>\n", prefix, base64.StdEncoding.EncodeToString(am.Body))
		return
	}

	// Deserialize into correct type.
	v := reflect.New(reflect.TypeOf(bodyType)).Interface()
	if err := cbor.Unmarshal(am.Body, v); err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		fmt.Fprintf(w, "%s<malformed: %s>\n", prefix, base64.StdEncoding.EncodeToString(am.Body))
		return
	}

	// If the body type supports pretty printing, use that.
	if pp, ok := v.(prettyprint.PrettyPrinter); ok {
		pp.PrettyPrint(ctx, prefix, w)
		return
	}

	// Otherwise, just serialize into JSON and display that.
	data, err := json.MarshalIndent(v, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s  <raw: %s>\n", prefix, base64.StdEncoding.EncodeToString(am.Body))
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// PrettyPrint writes a pretty-printed representation of ActionExecuteMessage to the given writer.
func (am ActionExecuteMessage) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sMethod: %s\n", prefix, am.Method)
	fmt.Fprintf(w, "%sBody:\n", prefix)
	am.PrettyPrintBody(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of ActionExecuteMessage that can be used for pretty printing.
func (am ActionExecuteMessage) PrettyType() (any, error) {
	bodyType := am.Method.BodyType()
	if bodyType == nil {
		return nil, fmt.Errorf("unknown method body type")
	}

	// Deserialize into correct type.
	body := reflect.New(reflect.TypeOf(bodyType)).Interface()
	if err := cbor.Unmarshal(am.Body, body); err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction body: %w", err)
	}

	// If the body type supports pretty printing, use that.
	if pp, ok := body.(prettyprint.PrettyPrinter); ok {
		var err error
		if body, err = pp.PrettyType(); err != nil {
			return nil, fmt.Errorf("failed to pretty print transaction body: %w", err)
		}
	}

	return &PrettyActionExecuteMessage{
		Method: am.Method,
		Body:   body,
	}, nil
}

// PrettyActionExecuteMessage is used for pretty-printing execute message actions so that the actual
// content is displayed instead of the binary blob.
//
// It should only be used for pretty printing.
type PrettyActionExecuteMessage struct {
	Method transaction.MethodName `json:"method"`
	Body   any                    `json:"body,omitempty"`
}

// ActionUpdateWithdrawPolicy is the action to update the withdraw policy for a given address.
type ActionUpdateWithdrawPolicy struct {
	// Address is the address the policy update is for.
	Address staking.Address `json:"address"`
	// Policy is the new withdraw policy.
	Policy WithdrawPolicy `json:"policy"`
}

// Validate validates the given action.
func (au *ActionUpdateWithdrawPolicy) Validate() error {
	if !au.Address.IsValid() {
		return fmt.Errorf("malformed address in update withdraw policy")
	}
	if err := au.Policy.Validate(); err != nil {
		return fmt.Errorf("malformed withdraw policy: %w", err)
	}
	return nil
}

// Authorities returns the authorities of the given vault that can authorize this action.
func (au *ActionUpdateWithdrawPolicy) Authorities(vault *Vault) []*Authority {
	return []*Authority{
		&vault.AdminAuthority,
	}
}

// PrettyPrint writes a pretty-printed representation of ActionUpdateWithdrawPolicy to the given
// writer.
func (au ActionUpdateWithdrawPolicy) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAddress: %s\n", prefix, au.Address)
	fmt.Fprintf(w, "%sPolicy:\n", prefix)
	au.Policy.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of ActionUpdateWithdrawPolicy that can be used for pretty
// printing.
func (au ActionUpdateWithdrawPolicy) PrettyType() (any, error) {
	return au, nil
}

// ActionUpdateAuthority is the action to update one of the vault authorities.
type ActionUpdateAuthority struct {
	// AdminAuthority is the new admin authority. If the field is nil no update should be done.
	AdminAuthority *Authority `json:"admin_authority,omitempty"`
	// SuspendAuthority is the new suspend authority. If the field is nil no update should be done.
	SuspendAuthority *Authority `json:"suspend_authority,omitempty"`
}

// Validate validates the given action.
func (au *ActionUpdateAuthority) Validate(params *ConsensusParameters) error {
	var authorities int
	if au.AdminAuthority != nil {
		if err := au.AdminAuthority.Validate(params); err != nil {
			return fmt.Errorf("malformed updated admin authority: %w", err)
		}
		authorities++
	}
	if au.SuspendAuthority != nil {
		if err := au.SuspendAuthority.Validate(params); err != nil {
			return fmt.Errorf("malformed updated suspend authority: %w", err)
		}
		authorities++
	}
	if authorities == 0 {
		return fmt.Errorf("at least one authority must be updated")
	}
	return nil
}

// Authorities returns the authorities of the given vault that can authorize this action.
func (au *ActionUpdateAuthority) Authorities(vault *Vault) []*Authority {
	return []*Authority{
		&vault.AdminAuthority,
	}
}

// Apply applies the authority update to the given vault.
func (au *ActionUpdateAuthority) Apply(vault *Vault) {
	if au.AdminAuthority != nil {
		vault.AdminAuthority = *au.AdminAuthority
	}
	if au.SuspendAuthority != nil {
		vault.SuspendAuthority = *au.SuspendAuthority
	}
}

// PrettyPrint writes a pretty-printed representation of ActionUpdateAuthority to the given
// writer.
func (au ActionUpdateAuthority) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	if au.AdminAuthority != nil {
		fmt.Fprintf(w, "%sNew admin authority:\n", prefix)
		au.AdminAuthority.PrettyPrint(ctx, prefix+"  ", w)
	}
	if au.SuspendAuthority != nil {
		fmt.Fprintf(w, "%sNew suspend authority:\n", prefix)
		au.SuspendAuthority.PrettyPrint(ctx, prefix+"  ", w)
	}
}

// PrettyType returns a representation of ActionUpdateAuthority that can be used for pretty
// printing.
func (au ActionUpdateAuthority) PrettyType() (any, error) {
	return au, nil
}
