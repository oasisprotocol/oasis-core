// Package api defines the staking application API for other applications.
package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

type messageKind uint8

// MessageAccountHook is the message kind for dispatching account hooks. The message itself
// implements the AccountHookInvocation interface.
//
// Only the module that can handle the given destination should respond. The response value
// depends on the hook.
var MessageAccountHook = messageKind(0)

// AccountHookInvocation is the message body for dispatching account hooks.
type AccountHookInvocation interface {
	// Kind is the invoked hook kind.
	Kind() staking.HookKind

	// DestinationMatches checks whether the destination matches the given destination.
	DestinationMatches(dst staking.HookDestination) bool
}

// WithdrawHookInvocation is the message body for HookKindWithdraw hook dispatch.
type WithdrawHookInvocation struct {
	// Destination is the configured hook destination.
	Destination staking.HookDestination
	// From is the address of the source account.
	From staking.Address
	// To is the address of the account that is attempting withdrawal.
	To staking.Address
	// Amount is the amount that is being withdrawn.
	Amount *quantity.Quantity
}

// Kind is the invoked hook kind.
func (wh *WithdrawHookInvocation) Kind() staking.HookKind {
	return staking.HookKindWithdraw
}

// DestinationMatches checks whether the destination matches the given destination.
func (wh *WithdrawHookInvocation) DestinationMatches(dst staking.HookDestination) bool {
	return wh.Destination == dst
}
